rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44d150b890d0d9440e430d47f2b5aeb2c6b5148bbe8cfabf83dcb4f89abdef2e"

  strings:
    $x1  = "{ \"username\":\"Z-Builder\",\"avatar_url\":\"https://cdn.discordapp.com/icons/745016440569987098/56ce57aa24fd66dc9a39fc03b48f94" ascii
    $s2  = "{ \"username\":\"Z-Builder\",\"avatar_url\":\"https://cdn.discordapp.com/icons/745016440569987098/56ce57aa24fd66dc9a39fc03b48f94" ascii
    $s3  = "{ \"username\":\"Z-Builder\",\"avatar_url\":\"https://cdn.discordapp.com/icons/745016440569987098/56ce57aa24fd66dc9a39fc03b48f94" ascii
    $s4  = "{ \"username\":\"Z-Builder\",\"avatar_url\":\"https://cdn.discordapp.com/icons/745016440569987098/56ce57aa24fd66dc9a39fc03b48f94" ascii
    $s5  = "{ \"username\":\"Z-Builder\",\"avatar_url\":\"https://cdn.discordapp.com/icons/745016440569987098/56ce57aa24fd66dc9a39fc03b48f94" ascii
    $s6  = "{ \"username\":\"Z-Builder\",\"avatar_url\":\"https://cdn.discordapp.com/icons/745016440569987098/56ce57aa24fd66dc9a39fc03b48f94" ascii
    $s7  = "Password: `" fullword ascii
    $s8  = "**Password: **`" fullword ascii
    $s9  = "size=128\",\"embeds\":[{\"title\":\"__**Here are all account(s) on the PC (besides recycle bin)! ~Z-Builder**__\",\"description" ascii
    $s10 = "size=128\",\"embeds\":[{\"title\":\"__**Here are the browser credentials! ~Z-Builder**__\",\"description\":\"" fullword ascii
    $s11 = "size=128\",\"embeds\":[{\"title\":\"__**Got an account! ~Z-Builder**__\",\"description\":\"" fullword ascii
    $s12 = "size=128\",\"embeds\":[{\"title\":\"__**Here are the recovered account(s)! ~Z-Builder**__\",\"description\":\"" fullword ascii
    $s13 = "size=128\",\"embeds\":[{\"title\":\"__**Traced an account! ~Z-Builder**__\",\"description\":\"" fullword ascii
    $s14 = "No password found" fullword ascii
    $s15 = "size=128\",\"embeds\":[{\"title\":\"__**Registry string! ~Z-Builder**__\",\"description\":\"```" fullword ascii
    $s16 = "**MAC address(es): **`" fullword ascii
    $s17 = "**IP address: **`" fullword ascii
    $s18 = "No discord token found" fullword ascii
    $s19 = "Error!+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-" fullword ascii
    $s20 = "**Discord token: **`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}
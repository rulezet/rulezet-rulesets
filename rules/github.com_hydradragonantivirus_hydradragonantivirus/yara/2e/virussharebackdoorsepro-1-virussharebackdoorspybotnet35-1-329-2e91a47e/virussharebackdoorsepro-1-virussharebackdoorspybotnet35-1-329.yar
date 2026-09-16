import "pe"
rule _VirusShareBackDoorSepro_1_VirusShareBackDoorSpyBotNET35_1_329 {
  meta:
    description = "datamaliciousorder - from files VirusShareBackDoorSepro_1.vir, VirusShareBackDoorSpyBotNET35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b8fb7ba5b8df9b78b495cd8bf6dcfa9f2c2788ca14db5f0a8c6f764477e8651"
    hash2       = "09f0de084878957eed32dd67002c17a4d2a888e82bdb02de039605fee83e8f8f"

  strings:
    $s1  = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**OS Info**\",\"value\":\"Operating System Name - " fullword wide
    $s2  = "\",\"inline\":true},{\"name\":\"**Processor**\",\"value\":\"CPU - " fullword wide
    $s3  = "\",\"inline\":false},{\"name\":\"**GPU**\",\"value\":\"Video Processor - " fullword wide
    $s4  = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier" fullword wide
    $s5  = "\\nOperating System Architecture - " fullword wide
    $s6  = "\"},\"footer\":{\"text\":\"Mercurial Grabber | github.com/nightfallgt/mercurial-grabber\"}}],\"username\": \"Mercurial Grabber\"" wide
    $s7  = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**IP Address Info**\",\"value\":\"IP Address - " fullword wide
    $s8  = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**Windows Product Key**\",\"value\":\"Product Key - " fullword wide
    $s9  = "\",\"inline\":true}],\"footer\":{\"text\":\"Mercurial Grabber | github.com/nightfallgt/mercurial-grabber\"}}],\"username\": \"Me" wide
    $s10 = "\",\"inline\":false}],\"footer\":{\"text\":\"Mercurial Grabber | github.com/nightfallgt/mercurial-grabber\"}}],\"username\": \"M" wide
    $s11 = "\\nDriver Version  - " fullword wide
    $s12 = "\\Google\\Chrome\\User Data\\default\\Login Data" fullword wide
    $s13 = "password: " fullword wide
    $s14 = "---------------- mercurial grabber ----------------" fullword wide
    $s15 = "Drive {0}\\ - {1}" fullword wide
    $s16 = "{\"content\": \"\",  \"embeds\":[{\"color\":0,\"fields\":[{\"name\":\"**Account Info**\",\"value\":\"User ID: " fullword wide
    $s17 = "\",\"inline\":false},{\"name\":\"**Memory**\",\"value\":\"Memory - " fullword wide
    $s18 = "HARDWARE\\Description\\System\\Logical Unit Id 0" fullword wide
    $s19 = "\\\\Opera Software\\Opera Stable" fullword wide
    $s20 = "request is not a http request" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}
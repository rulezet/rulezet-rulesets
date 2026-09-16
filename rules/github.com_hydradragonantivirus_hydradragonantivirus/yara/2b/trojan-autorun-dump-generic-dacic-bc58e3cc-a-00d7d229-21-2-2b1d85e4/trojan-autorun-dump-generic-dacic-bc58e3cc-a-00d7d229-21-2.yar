rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_21_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "711e53c01b577740e83332da6991834c026421ce081375d5826c3ba2562a4d20"

  strings:
    $s1  = "Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=C:\\Users\\DELL\\Documents\\telephone.mdf;Integrated Security=True;Connect " wide
    $s2  = " SELECT * FROM [dbo].[Table] WHERE ContactNumber='" fullword wide
    $s3  = " SELECT * FROM [dbo].[Table] WHERE email='" fullword wide
    $s4  = "Delete  Contact" fullword wide
    $s5  = "Update Contact" fullword wide
    $s6  = "' WHERE ContactNumber='" fullword wide
    $s7  = "Create New Contact" fullword wide
    $s8  = "DELETE FROM [dbo].[Table] WHERE ContactNumber='" fullword wide
    $s9  = "Telephone Directory" fullword wide
    $s10 = "Be True, Be Happy" fullword wide
    $s11 = "Enter all fields" fullword wide
    $s12 = "Contact updated" fullword wide
    $s13 = "Server busy, try again later" fullword wide
    $s14 = "Update contact" fullword wide
    $s15 = "Alter fields" fullword wide
    $s16 = "Enter atleast one field" fullword wide
    $s17 = " SELECT * FROM [dbo].[Table] WHERE Location='" fullword wide
    $s18 = "Phone Number : " fullword wide
    $s19 = "Find record" fullword wide
    $s20 = "(phone number)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}
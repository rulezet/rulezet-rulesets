rule VirusShareTrojanStarter7472 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanStarter7472.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f498998ca81fa00f797727fd0209c7207ad8a2b0703e2ca12f5e309364c24d8f"

  strings:
    $x1  = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
    $x2  = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
    $s3  = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture" ascii
    $s4  = "frank@hotmail.com" fullword wide
    $s5  = "Drag Target TextBox that doesn't allow drop" fullword wide
    $s6  = "Drag Target TextBox that allows drop" fullword wide
    $s7  = "2Dane Falte @ Copy Right 2007 - All Rights Reserved" fullword ascii
    $s8  = "Empty PictureBox as drag target" fullword wide
    $s9  = "Drag Target PictureBox control" fullword wide
    $s10 = "Instructional Text Label for Example 3, drag target" fullword wide
    $s11 = "Instructional Text Label for Example 2, drag target" fullword wide
    $s12 = "Instructional Text Label for Example 1, drag targets" fullword wide
    $s13 = "Drag Target TreeView" fullword wide
    $s14 = "Dane Falte @ Copy Right 2007 - All Rights Reserved" fullword wide
    $s15 = "neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPeJ" fullword ascii
    $s16 = "An e-Mail address in the form name@domain.com. Name and DomainName can have multiple names separated by a period." fullword wide
    $s17 = "An error was encountered when attempting to parse the source text. This is often caused by an invalid regex pattern.  Check your" wide
    $s18 = "The file name is (MadeUp.txt) " fullword wide
    $s19 = "Label with instructional text on dropping the picture to the other PictureBox control." fullword wide
    $s20 = "Label with instructional text on dropping node onto TreeView" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}
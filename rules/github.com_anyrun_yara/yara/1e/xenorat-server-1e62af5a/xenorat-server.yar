rule XenoRAT_server {
   meta:
      description = "Detects XenoRAT server"
      author = "Any.Run"
      reference = "https://github.com/moom825/xeno-rat"
      date = "2024-01-17"
      
      hash1 = "020D6667BE8E017E0B432B228A9097CFFE9E5CA248EECAF566151E4E2BD7195B" 
      hash2 = "B61E4D30AF50474AED593EC748E4A88875A7B492A319EDC2FD44B9F51B094769"
           
      url1 = "https://app.any.run/tasks/95ab175f-88d8-4e9e-9283-8e0fe2a7335c"
      url2 = "https://app.any.run/tasks/b6ad1585-e5e8-49f5-bc36-7fd91e8c9fd8"
      
   strings:
      $x1 = "The name of this tool is xeno-rat. Why is it called that? Well, to be honest, it just sounded nice." ascii fullword
      $x2 = "xeno_rat_server" ascii
      $x3 = "xeno rat server" ascii wide
      $x4 = "Xeno-rat: Created by moom825" wide fullword

      $s1 = "C:\\Windows\\System32\\rundll32.exe shell32.dll,#61" fullword wide
      $s2 = "Hvnc_Load" fullword ascii
      $s3 = "KeyLogger_Load" fullword ascii
      $s4 = "Live Microphone" fullword wide
      $s5 = "Windir + Disk Cleanup" fullword wide
      $s6 = "Uac Bypass" fullword wide
      $s7 = "Current Password: 1234" fullword wide
      $s8 = "plugins\\Hvnc.dll" fullword wide
      $s9 = "hidden_desktop" fullword wide
      $s10 = "moom825" ascii
      
      
   condition:
      uint16(0) == 0x5a4d and
      (1 of ($x*) or 7 of ($s*))
}
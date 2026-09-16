rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52690baae3a6bd6c645d3434fc5016382e416cb86c21dab5635e846f6cf8c253"

  strings:
    $s1  = "September\"Unable to find a Table of Contents$No topic-based help system installed" fullword wide
    $s2  = "#No OnGetItem event handler assigned(A style named %s has not been registered" fullword wide
    $s3  = "UTF-7%Cannot remove shell notification icon\"PageControl must first be assigned\"%s requires Windows Vista or later" fullword wide
    $s4  = "AVisual C++ CRT: Not enough memory to complete call to strerror." fullword ascii
    $s5  = "Space documentation MvvmBase Export Tool" fullword wide
    $s6  = "Feathering" fullword wide
    $s7  = "Assign Coordinates,Create a new rose diagram" fullword wide
    $s8  = "Ternary Line Scatter Plot\"Create a new piper plot" fullword wide
    $s9  = "Piper Plot6Create a new piper class plot" fullword wide
    $s10 = "Piper Class Scatter Plot/Create a new box-whisker plot" fullword wide
    $s11 = "Lock Aspect Ratio" fullword wide
    $s12 = "Rounded Rect" fullword wide
    $s13 = "Brush Properties!Click to specify brush properties" fullword wide
    $s14 = "Load Brush" fullword wide
    $s15 = "Eraser Opacity" fullword wide
    $s16 = ";Create a new floating bar graph" fullword wide
    $s17 = "Print MultipleLAssign coordinate to an object to allow it to be digitzed" fullword wide
    $s18 = "Polar Rose Diagram6Create a new ternary diagram" fullword wide
    $s19 = "XExtract coordinates from a plot by fixing the cursor to the selected plot" fullword wide
    $s20 = "Digitize Fixed" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}
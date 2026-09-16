import "pe"
rule ASProtect_V2_X_Registered____Alexey_Solodovnikov_____Sign_By_fly {
  strings:
    $a0 = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }

  condition:
    $a0 at pe.entry_point
}
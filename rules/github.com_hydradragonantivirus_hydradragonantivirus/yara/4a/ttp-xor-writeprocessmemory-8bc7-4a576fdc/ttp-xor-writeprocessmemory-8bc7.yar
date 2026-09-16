rule TTP_XOR_WriteProcessMemory_8bc7 {
  strings:
    $key_8bc7 = { dc b5 [2] ee 97 [2] e8 a2 [2] c6 a2 [2] f9 be }

  condition:
    any of them
}
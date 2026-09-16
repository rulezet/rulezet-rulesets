rule TTP_XOR_WriteProcessMemory_abb6 {
  strings:
    $key_abb6 = { fc c4 [2] ce e6 [2] c8 d3 [2] e6 d3 [2] d9 cf }

  condition:
    any of them
}
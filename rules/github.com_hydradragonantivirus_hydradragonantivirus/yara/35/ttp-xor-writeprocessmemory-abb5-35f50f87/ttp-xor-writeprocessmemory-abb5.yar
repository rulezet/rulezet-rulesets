rule TTP_XOR_WriteProcessMemory_abb5 {
  strings:
    $key_abb5 = { fc c7 [2] ce e5 [2] c8 d0 [2] e6 d0 [2] d9 cc }

  condition:
    any of them
}
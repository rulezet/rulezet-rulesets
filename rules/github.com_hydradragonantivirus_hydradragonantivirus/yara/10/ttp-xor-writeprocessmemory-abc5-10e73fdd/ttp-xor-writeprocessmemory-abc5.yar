rule TTP_XOR_WriteProcessMemory_abc5 {
  strings:
    $key_abc5 = { fc b7 [2] ce 95 [2] c8 a0 [2] e6 a0 [2] d9 bc }

  condition:
    any of them
}
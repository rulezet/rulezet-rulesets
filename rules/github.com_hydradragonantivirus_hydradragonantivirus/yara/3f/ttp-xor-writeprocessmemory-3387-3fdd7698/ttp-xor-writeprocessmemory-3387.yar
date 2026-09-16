rule TTP_XOR_WriteProcessMemory_3387 {
  strings:
    $key_3387 = { 64 f5 [2] 56 d7 [2] 50 e2 [2] 7e e2 [2] 41 fe }

  condition:
    any of them
}
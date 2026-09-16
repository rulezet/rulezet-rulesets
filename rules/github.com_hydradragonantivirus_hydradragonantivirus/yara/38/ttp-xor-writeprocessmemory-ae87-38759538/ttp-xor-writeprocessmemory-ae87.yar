rule TTP_XOR_WriteProcessMemory_ae87 {
  strings:
    $key_ae87 = { f9 f5 [2] cb d7 [2] cd e2 [2] e3 e2 [2] dc fe }

  condition:
    any of them
}
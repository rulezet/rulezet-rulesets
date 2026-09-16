rule TTP_XOR_WriteProcessMemory_0f93 {
  strings:
    $key_0f93 = { 58 e1 [2] 6a c3 [2] 6c f6 [2] 42 f6 [2] 7d ea }

  condition:
    any of them
}
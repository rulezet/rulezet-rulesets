rule TTP_XOR_WriteProcessMemory_a393 {
  strings:
    $key_a393 = { f4 e1 [2] c6 c3 [2] c0 f6 [2] ee f6 [2] d1 ea }

  condition:
    any of them
}
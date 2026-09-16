rule TTP_XOR_WriteProcessMemory_2893 {
  strings:
    $key_2893 = { 7f e1 [2] 4d c3 [2] 4b f6 [2] 65 f6 [2] 5a ea }

  condition:
    any of them
}
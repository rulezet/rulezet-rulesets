rule TTP_XOR_WriteProcessMemory_027a {
  strings:
    $key_027a = { 55 08 [2] 67 2a [2] 61 1f [2] 4f 1f [2] 70 03 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_9fc7 {
  strings:
    $key_9fc7 = { c8 b5 [2] fa 97 [2] fc a2 [2] d2 a2 [2] ed be }

  condition:
    any of them
}
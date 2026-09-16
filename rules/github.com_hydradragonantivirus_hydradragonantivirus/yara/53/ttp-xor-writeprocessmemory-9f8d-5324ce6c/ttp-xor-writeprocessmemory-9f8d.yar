rule TTP_XOR_WriteProcessMemory_9f8d {
  strings:
    $key_9f8d = { c8 ff [2] fa dd [2] fc e8 [2] d2 e8 [2] ed f4 }

  condition:
    any of them
}
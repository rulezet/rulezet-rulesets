rule TTP_XOR_WriteProcessMemory_9f9a {
  strings:
    $key_9f9a = { c8 e8 [2] fa ca [2] fc ff [2] d2 ff [2] ed e3 }

  condition:
    any of them
}
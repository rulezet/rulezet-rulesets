rule TTP_XOR_WriteProcessMemory_aabb {
  strings:
    $key_aabb = { fd c9 [2] cf eb [2] c9 de [2] e7 de [2] d8 c2 }

  condition:
    any of them
}
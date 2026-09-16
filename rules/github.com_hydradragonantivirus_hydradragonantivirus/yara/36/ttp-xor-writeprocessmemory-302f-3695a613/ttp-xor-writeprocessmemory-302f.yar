rule TTP_XOR_WriteProcessMemory_302f {
  strings:
    $key_302f = { 67 5d [2] 55 7f [2] 53 4a [2] 7d 4a [2] 42 56 }

  condition:
    any of them
}
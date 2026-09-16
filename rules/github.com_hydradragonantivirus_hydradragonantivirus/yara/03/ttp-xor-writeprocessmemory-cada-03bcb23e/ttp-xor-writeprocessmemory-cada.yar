rule TTP_XOR_WriteProcessMemory_cada {
  strings:
    $key_cada = { 9d a8 [2] af 8a [2] a9 bf [2] 87 bf [2] b8 a3 }

  condition:
    any of them
}
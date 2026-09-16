rule TTP_XOR_WriteProcessMemory_fabf {
  strings:
    $key_fabf = { ad cd [2] 9f ef [2] 99 da [2] b7 da [2] 88 c6 }

  condition:
    any of them
}
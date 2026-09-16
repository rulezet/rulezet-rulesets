rule TTP_XOR_WriteProcessMemory_8bbf {
  strings:
    $key_8bbf = { dc cd [2] ee ef [2] e8 da [2] c6 da [2] f9 c6 }

  condition:
    any of them
}
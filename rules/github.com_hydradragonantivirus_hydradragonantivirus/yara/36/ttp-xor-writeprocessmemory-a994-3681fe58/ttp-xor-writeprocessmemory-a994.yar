rule TTP_XOR_WriteProcessMemory_a994 {
  strings:
    $key_a994 = { fe e6 [2] cc c4 [2] ca f1 [2] e4 f1 [2] db ed }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_e828 {
  strings:
    $key_e828 = { bb 47 [2] 9f 49 [2] b4 65 [2] 9a 47 [2] 8e 5c [2] 81 46 [2] 9f 5b [2] 9d 5a [2] 86 5c [2] 9a 5b [2] 86 74 }

  condition:
    any of them
}
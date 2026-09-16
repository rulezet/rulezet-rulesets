rule TTP_XOR_QUAD_CurrentVersionRun_3dee {
  strings:
    $key_3dee = { 6e 81 [2] 4a 8f [2] 61 a3 [2] 4f 81 [2] 5b 9a [2] 54 80 [2] 4a 9d [2] 48 9c [2] 53 9a [2] 4f 9d [2] 53 b2 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_eaf9 {
  strings:
    $key_eaf9 = { b9 96 [2] 9d 98 [2] b6 b4 [2] 98 96 [2] 8c 8d [2] 83 97 [2] 9d 8a [2] 9f 8b [2] 84 8d [2] 98 8a [2] 84 a5 }

  condition:
    any of them
}
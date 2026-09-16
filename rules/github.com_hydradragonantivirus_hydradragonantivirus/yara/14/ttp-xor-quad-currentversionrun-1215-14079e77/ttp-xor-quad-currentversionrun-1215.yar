rule TTP_XOR_QUAD_CurrentVersionRun_1215 {
  strings:
    $key_1215 = { 41 7a [2] 65 74 [2] 4e 58 [2] 60 7a [2] 74 61 [2] 7b 7b [2] 65 66 [2] 67 67 [2] 7c 61 [2] 60 66 [2] 7c 49 }

  condition:
    any of them
}
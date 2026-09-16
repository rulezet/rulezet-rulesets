rule TTP_XOR_QUAD_CurrentVersionRun_ffb8 {
  strings:
    $key_ffb8 = { ac d7 [2] 88 d9 [2] a3 f5 [2] 8d d7 [2] 99 cc [2] 96 d6 [2] 88 cb [2] 8a ca [2] 91 cc [2] 8d cb [2] 91 e4 }

  condition:
    any of them
}
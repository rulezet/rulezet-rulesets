rule TTP_XOR_QUAD_CurrentVersionRun_06bf {
  strings:
    $key_06bf = { 55 d0 [2] 71 de [2] 5a f2 [2] 74 d0 [2] 60 cb [2] 6f d1 [2] 71 cc [2] 73 cd [2] 68 cb [2] 74 cc [2] 68 e3 }

  condition:
    any of them
}
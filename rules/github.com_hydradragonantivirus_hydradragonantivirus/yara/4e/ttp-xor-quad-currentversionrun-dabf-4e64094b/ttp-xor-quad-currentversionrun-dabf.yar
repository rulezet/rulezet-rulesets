rule TTP_XOR_QUAD_CurrentVersionRun_dabf {
  strings:
    $key_dabf = { 89 d0 [2] ad de [2] 86 f2 [2] a8 d0 [2] bc cb [2] b3 d1 [2] ad cc [2] af cd [2] b4 cb [2] a8 cc [2] b4 e3 }

  condition:
    any of them
}
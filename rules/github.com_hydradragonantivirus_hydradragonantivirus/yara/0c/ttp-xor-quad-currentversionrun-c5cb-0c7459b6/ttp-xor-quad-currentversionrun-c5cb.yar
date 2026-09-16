rule TTP_XOR_QUAD_CurrentVersionRun_c5cb {
  strings:
    $key_c5cb = { 96 a4 [2] b2 aa [2] 99 86 [2] b7 a4 [2] a3 bf [2] ac a5 [2] b2 b8 [2] b0 b9 [2] ab bf [2] b7 b8 [2] ab 97 }

  condition:
    any of them
}
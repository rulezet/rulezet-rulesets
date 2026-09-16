rule TTP_XOR_QUAD_CurrentVersionRun_b1b9 {
  strings:
    $key_b1b9 = { e2 d6 [2] c6 d8 [2] ed f4 [2] c3 d6 [2] d7 cd [2] d8 d7 [2] c6 ca [2] c4 cb [2] df cd [2] c3 ca [2] df e5 }

  condition:
    any of them
}
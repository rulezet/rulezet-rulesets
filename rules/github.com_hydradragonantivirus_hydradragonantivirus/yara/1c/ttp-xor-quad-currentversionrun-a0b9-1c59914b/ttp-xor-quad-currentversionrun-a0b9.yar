rule TTP_XOR_QUAD_CurrentVersionRun_a0b9 {
  strings:
    $key_a0b9 = { f3 d6 [2] d7 d8 [2] fc f4 [2] d2 d6 [2] c6 cd [2] c9 d7 [2] d7 ca [2] d5 cb [2] ce cd [2] d2 ca [2] ce e5 }

  condition:
    any of them
}
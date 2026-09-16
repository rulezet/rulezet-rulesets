rule TTP_XOR_QUAD_CurrentVersionRun_768c {
  strings:
    $key_768c = { 25 e3 [2] 01 ed [2] 2a c1 [2] 04 e3 [2] 10 f8 [2] 1f e2 [2] 01 ff [2] 03 fe [2] 18 f8 [2] 04 ff [2] 18 d0 }

  condition:
    any of them
}
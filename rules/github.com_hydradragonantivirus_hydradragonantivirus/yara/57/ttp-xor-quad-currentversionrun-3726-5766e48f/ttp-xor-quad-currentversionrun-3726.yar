rule TTP_XOR_QUAD_CurrentVersionRun_3726 {
  strings:
    $key_3726 = { 64 49 [2] 40 47 [2] 6b 6b [2] 45 49 [2] 51 52 [2] 5e 48 [2] 40 55 [2] 42 54 [2] 59 52 [2] 45 55 [2] 59 7a }

  condition:
    any of them
}
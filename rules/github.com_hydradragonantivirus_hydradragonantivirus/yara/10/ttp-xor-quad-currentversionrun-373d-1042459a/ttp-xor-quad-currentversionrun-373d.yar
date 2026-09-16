rule TTP_XOR_QUAD_CurrentVersionRun_373d {
  strings:
    $key_373d = { 64 52 [2] 40 5c [2] 6b 70 [2] 45 52 [2] 51 49 [2] 5e 53 [2] 40 4e [2] 42 4f [2] 59 49 [2] 45 4e [2] 59 61 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_303d {
  strings:
    $key_303d = { 63 52 [2] 47 5c [2] 6c 70 [2] 42 52 [2] 56 49 [2] 59 53 [2] 47 4e [2] 45 4f [2] 5e 49 [2] 42 4e [2] 5e 61 }

  condition:
    any of them
}
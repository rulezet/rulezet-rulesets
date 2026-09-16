rule TTP_XOR_QUAD_CurrentVersionRun_303c {
  strings:
    $key_303c = { 63 53 [2] 47 5d [2] 6c 71 [2] 42 53 [2] 56 48 [2] 59 52 [2] 47 4f [2] 45 4e [2] 5e 48 [2] 42 4f [2] 5e 60 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_054c {
  strings:
    $key_054c = { 56 23 [2] 72 2d [2] 59 01 [2] 77 23 [2] 63 38 [2] 6c 22 [2] 72 3f [2] 70 3e [2] 6b 38 [2] 77 3f [2] 6b 10 }

  condition:
    any of them
}
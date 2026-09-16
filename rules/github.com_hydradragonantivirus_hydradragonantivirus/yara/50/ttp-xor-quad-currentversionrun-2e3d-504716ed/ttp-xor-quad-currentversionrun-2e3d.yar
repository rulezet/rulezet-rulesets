rule TTP_XOR_QUAD_CurrentVersionRun_2e3d {
  strings:
    $key_2e3d = { 7d 52 [2] 59 5c [2] 72 70 [2] 5c 52 [2] 48 49 [2] 47 53 [2] 59 4e [2] 5b 4f [2] 40 49 [2] 5c 4e [2] 40 61 }

  condition:
    any of them
}
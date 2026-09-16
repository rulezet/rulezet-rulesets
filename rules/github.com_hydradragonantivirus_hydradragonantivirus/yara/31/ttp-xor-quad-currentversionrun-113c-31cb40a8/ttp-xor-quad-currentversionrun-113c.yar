rule TTP_XOR_QUAD_CurrentVersionRun_113c {
  strings:
    $key_113c = { 42 53 [2] 66 5d [2] 4d 71 [2] 63 53 [2] 77 48 [2] 78 52 [2] 66 4f [2] 64 4e [2] 7f 48 [2] 63 4f [2] 7f 60 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_113d {
  strings:
    $key_113d = { 42 52 [2] 66 5c [2] 4d 70 [2] 63 52 [2] 77 49 [2] 78 53 [2] 66 4e [2] 64 4f [2] 7f 49 [2] 63 4e [2] 7f 61 }

  condition:
    any of them
}
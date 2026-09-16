rule TTP_XOR_QUAD_CurrentVersionRun_052e {
  strings:
    $key_052e = { 56 41 [2] 72 4f [2] 59 63 [2] 77 41 [2] 63 5a [2] 6c 40 [2] 72 5d [2] 70 5c [2] 6b 5a [2] 77 5d [2] 6b 72 }

  condition:
    any of them
}
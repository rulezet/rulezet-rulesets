rule TTP_XOR_QUAD_CurrentVersionRun_513f {
  strings:
    $key_513f = { 02 50 [2] 26 5e [2] 0d 72 [2] 23 50 [2] 37 4b [2] 38 51 [2] 26 4c [2] 24 4d [2] 3f 4b [2] 23 4c [2] 3f 63 }

  condition:
    any of them
}
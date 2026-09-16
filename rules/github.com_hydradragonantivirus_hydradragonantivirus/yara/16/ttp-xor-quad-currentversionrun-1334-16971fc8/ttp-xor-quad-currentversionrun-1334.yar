rule TTP_XOR_QUAD_CurrentVersionRun_1334 {
  strings:
    $key_1334 = { 40 5b [2] 64 55 [2] 4f 79 [2] 61 5b [2] 75 40 [2] 7a 5a [2] 64 47 [2] 66 46 [2] 7d 40 [2] 61 47 [2] 7d 68 }

  condition:
    any of them
}
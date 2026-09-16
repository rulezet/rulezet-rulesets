rule OpenJPEG_dwt_norms_real__flt32___32_big_148_ {
  strings:
    $a0 = { 3f 80 00 00 3f fb 85 1f 40 85 a9 fc 41 06 72 b0 41 87 33 33 42 07 5c 29 42 87 61 48 43 07 4c cd 43 87 4c cd 44 07 39 9a 40 01 68 73 40 7f 4b c7 41 05 ae 14 41 88 51 ec 42 09 14 7b 42 89 42 8f 43 09 4c cd 43 89 4c cd 44 09 40 00 40 01 68 73 40 7f 4b c7 41 05 ae 14 41 88 51 ec 42 09 14 7b 42 89 42 8f 43 09 4c cd 43 89 4c cd 44 09 40 00 40 05 1e b8 40 77 5c 29 41 04 e9 79 41 89 70 a4 42 0a d7 0a 42 8b 2e 14 43 0b 4c cd 43 8b 4c cd 44 0b 4c cd }

  condition:
    $a0
}
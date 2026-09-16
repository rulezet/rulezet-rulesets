rule file_pdf_header {
  meta:
    description   = "Finds Portable Document Format (.pdf) files"
    last_modified = "2024-03-06"
    author        = "@petermstewart"
    DaysofYara    = "66/100"
    ref           = "https://en.wikipedia.org/wiki/PDF"

  condition:
    uint32(0) == 0x46445025
}
import "hash"
rule ccleaner_compromised_application {
    meta:
      author = "NVISIO"
      reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"
    condition:
        filesize == 7781592 and hash.sha256(0, filesize) == "36b36ee9515e0a60629d2c722b006b33e543dce1c8c2611053e0651a0bfdb2e9" or
        filesize == 7680216 and hash.sha256(0, filesize) == "6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9"
}
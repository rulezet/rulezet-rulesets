rule crime_sload_scheduledtask_dropper_strings {
  meta:
    id             = "01c51da8-71a5-449f-a609-933c37bc2e63"
    version        = "1.0"
    author         = "Sekoia.io"
    creation_date  = "2022-08-02"
    classification = "TLP:CLEAR"

  strings:
    $ = "$hh='hi'+'dd'+'en';"
    $ = "}else{\n$rs=0;\n}\n"
    $ = "kill -name *wershel*"

  condition:
    all of them
}
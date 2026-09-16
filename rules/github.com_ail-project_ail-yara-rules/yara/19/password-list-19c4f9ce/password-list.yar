rule password_list
{
    meta:
        author = "@KevTheHermit and @Plazmaz"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
                                        $data_format = /\b[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-]["|']?(:|\|)[^\b\s]+\b/

    condition:
        #data_format > 10

}